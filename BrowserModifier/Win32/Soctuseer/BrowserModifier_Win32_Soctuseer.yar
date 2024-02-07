
rule BrowserModifier_Win32_Soctuseer{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 57 45 5f 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  WWE_uninstall.exe
		$a_01_1 = {53 6f 63 69 61 32 53 65 61 72 63 } //00 00  Socia2Searc
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_2{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c 2d 61 70 70 73 2e 63 6f 6d 2f 73 32 73 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //00 00  http://install-apps.com/s2s_install.exe
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_3{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 03 00 00 32 00 "
		
	strings :
		$a_01_0 = {57 42 45 5f 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  WBE_uninstall.exe
		$a_01_1 = {53 6f 63 69 61 6c 32 53 65 20 42 72 6f 77 73 65 72 20 45 6e 68 61 6e 63 65 72 } //01 00  Social2Se Browser Enhancer
		$a_01_2 = {53 6f 63 69 61 32 53 65 61 72 20 42 72 6f 77 73 65 72 20 45 6e 68 61 6e 63 65 72 } //00 00  Socia2Sear Browser Enhancer
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_4{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 04 00 00 32 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } //32 00  搮汬猀慫獲楮k
		$a_01_1 = {77 61 6a 61 6d 5f 67 6f 62 6c 69 6e 2e 70 64 62 } //01 00  wajam_goblin.pdb
		$a_01_2 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 } //01 00  Social2S
		$a_01_3 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 68 00 } //00 00  Socia2Search
		$a_00_4 = {78 64 00 00 65 00 65 00 04 00 00 32 00 0e 01 2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 32 00 13 01 77 61 6a 61 6d 5f 67 6f 62 6c 69 6e 5f 36 34 2e 70 64 } //62 01 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_5{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 04 00 00 32 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } //32 00  搮汬猀慫獲楮k
		$a_01_1 = {77 61 6a 61 6d 5f 67 6f 62 6c 69 6e 5f 36 34 2e 70 64 62 } //01 00  wajam_goblin_64.pdb
		$a_01_2 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 } //01 00  Social2S
		$a_01_3 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 68 00 } //00 00  Socia2Search
		$a_00_4 = {78 79 00 00 03 00 03 00 03 00 00 01 00 22 01 57 00 57 00 45 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 01 00 } //20 01 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_6{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 57 00 45 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  WWE_uninstall.exe
		$a_01_1 = {2f 00 44 00 45 00 4c 00 45 00 54 00 45 00 5f 00 4f 00 4e 00 5f 00 43 00 4c 00 4f 00 53 00 45 00 } //01 00  /DELETE_ON_CLOSE
		$a_01_2 = {2f 00 4e 00 41 00 4d 00 45 00 20 00 53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 65 00 61 00 72 00 } //00 00  /NAME Social2Sear
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_7{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } //01 00  搮汬猀慫獲楮k
		$a_03_1 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 06 5c 73 72 63 5c 68 74 74 70 5f 69 6e 74 65 72 63 65 70 74 69 6f 6e 5c 90 05 10 04 30 2d 39 5f 2e 70 64 62 90 00 } //01 00 
		$a_01_2 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 } //00 00  Socia2Searc
		$a_00_3 = {78 91 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_8{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } //01 00  搮汬猀慫獲楮k
		$a_01_1 = {2e 64 6c 6c 00 62 75 6c 62 75 6c 00 } //01 00  搮汬戀汵畢l
		$a_01_2 = {37 00 66 00 35 00 65 00 64 00 38 00 35 00 64 00 2d 00 36 00 38 00 32 00 38 00 2d 00 34 00 66 00 39 00 32 00 2d 00 38 00 35 00 38 00 63 00 2d 00 66 00 34 00 30 00 62 00 30 00 61 00 63 00 36 00 38 00 31 00 33 00 38 00 } //01 00  7f5ed85d-6828-4f92-858c-f40b0ac68138
		$a_01_3 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 } //00 00  Socia2Searc
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_9{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } //01 00  搮汬猀慫獲楮k
		$a_01_1 = {3c 73 63 72 69 70 74 20 64 61 74 61 2d 74 79 70 65 3d 22 69 6e 6a 65 63 74 65 64 22 20 73 72 63 3d 22 25 31 25 25 32 25 25 33 25 25 34 25 22 3e 3c 2f 73 63 72 69 70 74 3e } //01 00  <script data-type="injected" src="%1%%2%%3%%4%"></script>
		$a_01_2 = {76 3d 64 25 31 25 26 6f 73 5f 6d 6a 3d 25 32 25 26 6f 73 5f 6d 6e 3d 25 33 25 26 6f 73 5f 62 69 74 6e 65 73 73 3d 25 34 25 } //01 00  v=d%1%&os_mj=%2%&os_mn=%3%&os_bitness=%4%
		$a_01_3 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 } //00 00  Socia2Searc
		$a_00_4 = {78 d5 00 } //00 16 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_10{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 14 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 } //01 00  Socia2Sear
		$a_01_1 = {77 74 66 21 20 63 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 74 68 65 20 74 68 72 65 61 64 } //01 00  wtf! cannot create the thread
		$a_01_2 = {37 00 66 00 35 00 65 00 64 00 38 00 35 00 64 00 2d 00 36 00 38 00 32 00 38 00 2d 00 34 00 66 00 39 00 32 00 2d 00 38 00 35 00 38 00 63 00 2d 00 66 00 34 00 30 00 62 00 30 00 61 00 63 00 36 00 38 00 31 00 33 00 38 00 } //01 00  7f5ed85d-6828-4f92-858c-f40b0ac68138
		$a_01_3 = {41 56 51 75 69 63 45 6e 63 72 79 70 74 65 64 50 61 63 6b 65 74 40 6e 65 74 40 40 } //01 00  AVQuicEncryptedPacket@net@@
		$a_01_4 = {41 56 71 75 69 63 5f 72 65 71 75 65 73 74 5f 70 61 72 73 65 72 40 68 74 74 70 5f 70 61 72 73 69 6e 67 40 40 } //00 00  AVquic_request_parser@http_parsing@@
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_11{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 55 75 6e 72 65 67 69 73 74 72 79 5f 64 72 69 76 65 72 40 40 } //01 00  AUunregistry_driver@@
		$a_01_1 = {41 55 70 72 65 70 61 72 65 5f 64 65 66 65 6e 73 65 5f 64 72 69 76 65 72 5f 75 70 64 61 74 65 40 40 } //01 00  AUprepare_defense_driver_update@@
		$a_01_2 = {41 55 75 6e 7a 69 70 5f 70 61 74 63 68 65 72 5f 73 65 72 76 69 63 65 40 40 } //01 00  AUunzip_patcher_service@@
		$a_01_3 = {41 55 3f 24 65 72 72 6f 72 5f 69 6e 66 6f 5f 69 6e 6a 65 63 74 6f 72 40 56 62 61 64 5f 66 6f 72 6d 61 74 5f 73 74 72 69 6e 67 40 69 6f 40 62 6f 6f 73 74 40 40 40 65 78 63 65 70 74 69 6f 6e 5f 64 65 74 61 69 6c 40 62 6f 6f 73 74 40 40 } //01 00  AU?$error_info_injector@Vbad_format_string@io@boost@@@exception_detail@boost@@
		$a_01_4 = {41 56 3f 24 5f 52 65 66 5f 63 6f 75 6e 74 5f 6f 62 6a 40 55 69 6e 6a 65 63 74 69 6f 6e 40 68 74 6d 6c 5f 69 6e 6a 65 63 74 69 6f 6e 40 40 40 73 74 64 40 40 } //00 00  AV?$_Ref_count_obj@Uinjection@html_injection@@@std@@
		$a_00_5 = {78 f4 00 } //00 0d 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_12{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 } //01 00  Social2S
		$a_01_1 = {42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 72 00 } //01 00  Browser Enhancer
		$a_01_2 = {6e 00 73 00 73 00 5c 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 41 00 20 00 2d 00 74 00 20 00 22 00 54 00 43 00 75 00 22 00 20 00 2d 00 69 00 20 00 22 00 } //01 00  nss\certutil -A -t "TCu" -i "
		$a_01_3 = {37 00 66 00 35 00 65 00 64 00 38 00 35 00 64 00 2d 00 36 00 38 00 32 00 38 00 2d 00 34 00 66 00 39 00 32 00 2d 00 38 00 35 00 38 00 63 00 2d 00 66 00 34 00 30 00 62 00 30 00 61 00 63 00 36 00 38 00 31 00 33 00 38 00 } //01 00  7f5ed85d-6828-4f92-858c-f40b0ac68138
		$a_81_4 = {2d 2d 61 70 70 6c 79 5f 73 65 61 72 63 68 70 61 67 65 5f 73 65 61 72 63 68 5f 70 72 6f 76 69 64 65 72 } //00 00  --apply_searchpage_search_provider
		$a_00_5 = {78 02 01 00 17 00 17 00 07 00 00 14 } //00 26 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_13{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 14 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 65 00 61 00 72 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } //01 00  Social2Sear Monitor
		$a_01_1 = {33 00 30 00 34 00 35 00 30 00 33 00 35 00 42 00 2d 00 33 00 43 00 31 00 34 00 2d 00 34 00 36 00 39 00 38 00 2d 00 38 00 41 00 43 00 34 00 2d 00 41 00 44 00 42 00 31 00 38 00 43 00 43 00 34 00 32 00 43 00 31 00 45 00 } //01 00  3045035B-3C14-4698-8AC4-ADB18CC42C1E
		$a_01_2 = {66 6f 6c 64 65 72 20 6f 66 20 77 61 6a 61 6d 20 64 6c 6c } //01 00  folder of wajam dll
		$a_01_3 = {70 61 74 68 20 74 6f 20 70 61 74 63 68 2e 7a 69 70 } //01 00  path to patch.zip
		$a_01_4 = {61 70 70 6c 79 20 61 20 64 6f 77 6e 6c 6f 61 64 65 64 20 70 61 74 63 68 } //01 00  apply a downloaded patch
		$a_01_5 = {69 6e 6a 65 63 74 20 64 6c 6c 20 69 6e 74 6f 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 } //01 00  inject dll into target process
		$a_01_6 = {6d 61 6e 75 61 6c 5f 6d 61 70 70 69 6e 67 5f 69 6e 6a 65 63 74 } //00 00  manual_mapping_inject
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_14{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 } //01 00  Social2S
		$a_01_1 = {2d 00 2d 00 70 00 61 00 74 00 63 00 68 00 5f 00 63 00 66 00 67 00 5f 00 66 00 69 00 6c 00 65 00 3d 00 } //01 00  --patch_cfg_file=
		$a_01_2 = {2d 00 2d 00 61 00 70 00 70 00 6c 00 79 00 5f 00 70 00 61 00 74 00 63 00 68 00 20 00 2d 00 2d 00 70 00 61 00 74 00 63 00 68 00 3d 00 } //01 00  --apply_patch --patch=
		$a_01_3 = {57 00 42 00 45 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  WBE_uninstall.exe
		$a_01_4 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 43 00 38 00 30 00 33 00 35 00 33 00 31 00 44 00 2d 00 30 00 36 00 44 00 38 00 2d 00 34 00 33 00 43 00 44 00 2d 00 42 00 44 00 35 00 33 00 2d 00 33 00 38 00 46 00 36 00 33 00 32 00 35 00 39 00 36 00 42 00 39 00 41 00 } //01 00  Global\C803531D-06D8-43CD-BD53-38F632596B9A
		$a_01_5 = {3c 73 63 72 69 70 74 20 64 61 74 61 2d 74 79 70 65 3d 22 69 6e 6a 65 63 74 65 64 22 20 73 72 63 3d 22 25 31 25 25 32 25 25 33 25 25 34 25 22 3e 3c 2f 73 63 72 69 70 74 3e } //01 00  <script data-type="injected" src="%1%%2%%3%%4%"></script>
		$a_01_6 = {77 74 66 21 20 75 6e 73 75 70 70 6f 72 74 65 64 20 70 61 74 63 68 20 74 79 70 65 3a 20 25 31 25 } //00 00  wtf! unsupported patch type: %1%
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_15{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {2d 2d 61 70 70 6c 79 5f 70 61 74 63 68 } //0a 00  --apply_patch
		$a_01_1 = {77 00 61 00 6a 00 61 00 6d 00 2e 00 64 00 6c 00 6c 00 } //01 00  wajam.dll
		$a_03_2 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 18 5c 73 72 63 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 2e 70 64 62 90 00 } //01 00 
		$a_03_3 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 6d 6f 74 69 2d 90 02 10 5c 73 72 63 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 2e 70 64 62 90 00 } //01 00 
		$a_03_4 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 06 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c 90 12 10 00 2e 70 64 62 90 00 } //01 00 
		$a_01_5 = {37 00 66 00 35 00 65 00 64 00 38 00 35 00 64 00 2d 00 36 00 38 00 32 00 38 00 2d 00 34 00 66 00 39 00 32 00 2d 00 38 00 35 00 38 00 63 00 2d 00 66 00 34 00 30 00 62 00 30 00 61 00 63 00 36 00 38 00 31 00 33 00 38 00 } //01 00  7f5ed85d-6828-4f92-858c-f40b0ac68138
		$a_01_6 = {2e 3f 41 56 41 73 6d 48 65 6c 70 65 72 42 61 73 65 40 62 6c 61 63 6b 62 6f 6e 65 40 40 } //01 00  .?AVAsmHelperBase@blackbone@@
		$a_01_7 = {2e 3f 41 56 3f 24 5f 52 65 66 5f 63 6f 75 6e 74 5f 64 65 6c 40 50 41 55 48 49 4e 53 54 41 4e 43 45 5f 5f 40 40 56 } //00 00  .?AV?$_Ref_count_del@PAUHINSTANCE__@@V
		$a_00_8 = {78 7f 01 00 15 00 15 00 08 00 00 } //0a 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Soctuseer_16{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {2d 2d 61 70 70 6c 79 5f 70 61 74 63 68 } //0a 00  --apply_patch
		$a_01_1 = {77 00 61 00 6a 00 61 00 6d 00 5f 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } //01 00  wajam_64.dll
		$a_03_2 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 18 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 5f 36 34 2e 70 64 62 90 00 } //01 00 
		$a_03_3 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 6d 6f 74 69 2d 90 02 10 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 61 6a 61 6d 5f 36 34 2e 70 64 62 90 00 } //01 00 
		$a_03_4 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 06 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c 90 05 10 04 30 2d 39 5f 2e 70 64 62 90 00 } //01 00 
		$a_03_5 = {44 3a 5c 6a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 73 74 61 62 6c 65 2d 90 02 06 5c 73 72 63 5c 53 65 72 76 69 63 65 52 75 6e 6e 65 72 5c 90 12 10 00 2e 70 64 62 90 00 } //01 00 
		$a_01_6 = {2e 3f 41 56 41 73 6d 48 65 6c 70 65 72 42 61 73 65 40 62 6c 61 63 6b 62 6f 6e 65 40 40 } //01 00  .?AVAsmHelperBase@blackbone@@
		$a_01_7 = {2e 3f 41 56 41 73 6d 48 65 6c 70 65 72 36 34 40 62 6c 61 63 6b 62 6f 6e 65 40 40 } //00 00  .?AVAsmHelper64@blackbone@@
		$a_00_8 = {80 10 00 00 b9 bf 95 00 9d 30 b0 } //20 8f 
	condition:
		any of ($a_*)
 
}