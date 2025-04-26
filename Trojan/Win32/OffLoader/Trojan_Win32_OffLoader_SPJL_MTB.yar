
rule Trojan_Win32_OffLoader_SPJL_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 2e 77 69 6e 64 6f 77 73 74 6f 6e 65 2e 77 65 62 73 69 74 65 2f 74 72 61 63 6b 5f 70 6f 6c 6f 73 45 55 2e 70 68 70 } //4 save.windowstone.website/track_polosEU.php
		$a_01_1 = {6a 65 77 65 6c 62 61 73 6b 65 74 62 61 6c 6c 2e 78 79 7a 2f 6c 69 63 61 2e 70 68 70 } //2 jewelbasketball.xyz/lica.php
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}