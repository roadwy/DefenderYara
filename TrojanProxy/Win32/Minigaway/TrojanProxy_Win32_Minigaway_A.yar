
rule TrojanProxy_Win32_Minigaway_A{
	meta:
		description = "TrojanProxy:Win32/Minigaway.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 61 74 65 77 61 79 3a 3a 43 47 61 74 65 77 61 79 33 3a 3a } //01 00  Gateway::CGateway3::
		$a_01_1 = {47 61 74 65 77 61 79 3a 3a 43 4c 69 73 74 65 6e 3a 3a } //01 00  Gateway::CListen::
		$a_01_2 = {47 61 74 65 77 61 79 3a 3a 43 54 75 6e 6e 65 6c 3a 3a } //01 00  Gateway::CTunnel::
		$a_01_3 = {47 61 74 65 77 61 79 3a 3a 43 53 6f 63 6b 73 55 6e 64 65 66 69 6e 65 64 3a 3a } //01 00  Gateway::CSocksUndefined::
		$a_01_4 = {2f 43 61 6c 6c 42 61 63 6b 2f 53 6f 6d 65 53 63 72 69 70 74 73 2f } //01 00  /CallBack/SomeScripts/
		$a_01_5 = {2f 70 65 72 6c 2f 73 63 72 69 70 74 73 2f 65 72 72 6f 72 4d 47 2e 70 6c } //01 00  /perl/scripts/errorMG.pl
		$a_01_6 = {2e 70 68 70 3f 73 6f 63 6b 73 5f 69 64 3d 25 64 26 63 68 65 63 6b 32 35 3d 25 64 } //02 00  .php?socks_id=%d&check25=%d
		$a_01_7 = {69 70 3a 70 6f 72 74 3d 25 73 3a 25 68 75 09 69 64 3d 25 6c 75 09 6c 69 73 74 65 6e 3d 25 68 75 09 6d 6f 64 3d 25 6c 75 } //02 00  灩瀺牯㵴猥┺畨椉㵤氥ॵ楬瑳湥┽畨洉摯┽畬
		$a_01_8 = {72 65 6c 3d 25 6c 75 25 25 09 6f 6e 6c 69 6e 65 3d 25 6c 75 09 72 65 63 6f 6e 6e 3d 25 6c 75 } //02 00 
		$a_01_9 = {61 74 2f 77 74 3d 25 6c 75 2f 25 6c 75 09 74 2f 73 3d 25 6c 75 2f 25 6c 75 09 75 72 65 63 2f 61 72 65 63 3d 25 6c 75 2f 25 6c 75 28 6d 73 65 63 29 } //02 00 
		$a_03_10 = {8b 45 f8 8d 3c 30 03 7b 04 8d 46 f4 e8 90 01 02 00 00 66 8b 47 08 ff 45 f4 66 89 46 fc 8b 47 0c 89 06 8b 45 f4 83 c6 10 3b 03 72 d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}