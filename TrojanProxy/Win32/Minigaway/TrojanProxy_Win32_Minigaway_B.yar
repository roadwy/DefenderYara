
rule TrojanProxy_Win32_Minigaway_B{
	meta:
		description = "TrojanProxy:Win32/Minigaway.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 43 61 6c 6c 42 61 63 6b 2f 53 6f 6d 65 53 63 72 69 70 74 73 2f 75 70 64 61 74 65 32 35 2e 70 68 70 3f 73 6f 63 6b 73 5f 69 64 3d 25 64 26 63 68 65 63 6b 32 35 3d 25 64 20 48 54 54 50 2f 31 2e 30 } //4 GET /CallBack/SomeScripts/update25.php?socks_id=%d&check25=%d HTTP/1.0
		$a_01_1 = {2e 44 45 46 41 55 4c 54 5c 53 6f 66 74 77 61 72 65 5c 41 4d 53 65 72 76 69 63 65 5c 43 61 6c 6c 42 61 63 6b } //3 .DEFAULT\Software\AMService\CallBack
		$a_01_2 = {20 3a 20 66 43 72 65 61 74 65 54 75 6e 6e 65 6c 57 69 74 68 43 6c 69 65 6e 74 53 69 64 65 20 3d 3d 20 4e 55 4c 4c } //3  : fCreateTunnelWithClientSide == NULL
		$a_01_3 = {50 4f 53 54 20 2f 43 61 6c 6c 42 61 63 6b 2f 53 6f 6d 65 53 63 72 69 70 74 73 2f 6d 67 73 4e 65 77 50 65 65 72 2e 70 68 70 20 48 54 54 50 2f 31 2e 30 } //3 POST /CallBack/SomeScripts/mgsNewPeer.php HTTP/1.0
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=13
 
}