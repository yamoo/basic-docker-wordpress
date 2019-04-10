<?php

  remove_action('wp_head','wp_generator');
  function remove_cssjs_ver2( $src ) {
      if ( strpos( $src, 'ver=' ) )
          $src = remove_query_arg( 'ver', $src );
      return $src;
  }
  add_filter( 'style_loader_src', 'remove_cssjs_ver2', 9999 );
  add_filter( 'script_loader_src', 'remove_cssjs_ver2', 9999 );
