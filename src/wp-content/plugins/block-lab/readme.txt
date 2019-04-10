=== Block Lab ===

Contributors: lukecarbis, ryankienstra, Stino11, rheinardkorf
Tags: Gutenberg, Blocks
Requires at least: 5.0
Tested up to: 5.1.1
Requires PHP: 5.4
Stable tag: 1.2.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl

A WordPress Admin interface and a simple templating system for building custom Gutenberg blocks.

== Description ==

With the Gutenberg update, WordPress users will increasingly look for the development of custom blocks to meet their unique needs. Block Lab reduces the development burden of building custom blocks through a simple and familiar WordPress Admin interface and an easy to learn templating system.

== Features ==

= A Familiar Experience =
Work within the WordPress admin with an interface you already know.

= Custom Fields =
Add from a growing list of available fields to your custom blocks.

= Simple Templating =
Let the plugin do the heavy lifting so you can use familiar WordPress development practices to build block templates.

= Developer Friendly Functions =
Simple to use functions, ready to render and work with the values stored through your custom block fields.

== Links ==
* [WordPress.org](https://wordpress.org/plugins/block-lab)
* [Github](https://github.com/getblocklab/block-lab)
* [Documentation](https://github.com/getblocklab/block-lab/wiki)
* [Support](https://wordpress.org/support/plugin/block-lab)

== Installation ==
= From Within WordPress =
* Visit Plugins > Add New
* Search for "Block Lab"
* Activate Block Lab from your Plugins page.

= Manually =
* Clone Block Lab into a working directory with `https://github.com/getblocklab/block-lab.git`
* `cd` into the `block-lab` directory, and run `npm install`
* Next, build the scripts and styles with `npm build`
* Move the `block-lab` folder to your `/wp-content/plugins/` directory
* Activate the Block Lab plugin through the Plugins menu in WordPress

== Frequently Asked Questions =
**Q: Do I need to write code to use this plugin?**
A: Although the plugin handles the majority of the work in building a custom block, you will need to build HTML templates to display the content of the block. You can learn how in the the developer documentation.

**Q: I have an idea for the plugin**
A: This plugin is open source and can only be better through community contribution. The GitHub repo is [here](https://github.com/getblocklab/block-lab).

**Q: Where can I find documentation for this plugin?**
A: [Here](https://github.com/getblocklab/block-lab/wiki)

== Contributing ==

See [Contributing to Block Lab](https://github.com/getblocklab/block-lab/blob/develop/CONTRIBUTING.md).

== Changelog ===
 
= 1.2.2 - 2019-04-05 =
* New: Block Editor redesign

= 1.2.1 - 2019-03-21 =

* New: Automatic stylesheet enqueuing. Now you can create custom stylesheets for individual blocks! [Read more here](https://github.com/getblocklab/block-lab/wiki/5.-Styling-Custom-Blocks).
* New: A User control type (for Block Lab Pro users)
* Fix: Various multiselect bug fixes, allowing for empty values in the multiselect control
 
= 1.2.0 - 2019-02-27 =

* New: Introducing Block Lab Pro!
* New: A setting for the number of rows to display in a Textarea control
* Fix: Allow negative numbers in Number and Range controls
 
= 1.1.3 - 2019-01-25 =

* New: Image field
 
= 1.1.2 - 2019-01-11 =

* New: Color field
* Fix: Incorrect output for empty fields
 
= 1.1.1 - 2018-12-14 =

* Fix: Undefined index error for multiselect and select fields
* Fix: Correct values now returned for boolean fields like checkbox and toggle
* Fix: Editor preview templates are back! Use the filename `preview-{blog slug}.php`
* Fix: "Field instructions" is now a single line text, and renamed to "Help Text"
* Fix: Slashes being added to field options
* Fix: Allow empty value for select and number fields
* Fix: Allow empty default values
 
= 1.1.0 - 2018-12-07 =

* New: Complete revamp of the in-editor preview
* New: Email field
* New: URL field
* New: Number field
* New: `block_config()` and `block_field_config` helper functions, to retrieve your block's configuration
* Fix: filemtime errors
* Fix: HTML tags were being merged together when previewed in the editor
* Fix: Problems with quotes and dashes in a block's title or field parameters
* Fix: `field_value()` sometimes returned the wrong value
* Fix: Incorrect values shown in the editor preview
 
= 1.0.1 - 2018-11-16 =

* New: Added "Save Draft" button, so you can save Blocks-in-Progress
* New: Better handling of the auto-slug feature, so you don't accidentally change your block's slug
* New: Better expanding / contracting of the Field settings
* New: Emoji (and special character) support! 😎
* Fix: Resolved Fatal Error that could occur in some environments
* Fix: Remove unused "Description" field
* Fix: Remove duplicate star icon
 
= 1.0.0 - 2018-11-14 =

*Rename!*
* Advanced Custom Blocks is now Block Lab

*Added*
* New control types (Radio, Checkbox, Toggle, Select, Range)
* Block icons
* Field location – add your block fields to the inspector
* List table refinements
* Field repeater table improvements

*Fixed*
* All the things. Probably not _all_ the things, but close.
 
= 0.1.2 - 2018-08-10 =

*Added*
* New properties `help`, `default` and `required` added to fields.
* Ability to import blocks from a `{theme}/blocks/blocks.json` file.
  Documentation still to be added.
* Gutenberg controls library updated preparing for `0.0.3`.

*Technical Changes* 
* Updated control architecture to improve development 
  and adding adding of additional controls. 
* Clean up enqueuing of scripts.
 
= 0.1 - 2018-08-03 =
* Initial release.