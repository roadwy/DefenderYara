
rule Trojan_BAT_Tedy_GNC_MTB{
	meta:
		description = "Trojan:BAT/Tedy.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6d 61 6e 61 20 62 72 65 61 6b 5c } //\Program Files\mana break\  01 00 
		$a_01_1 = {35 30 35 5c 35 30 35 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 66 75 63 6b 79 6f 75 77 61 72 65 2e 70 64 62 } //01 00  505\505\obj\Release\fuckyouware.pdb
		$a_01_2 = {66 75 63 6b 79 6f 75 77 61 72 65 2e 65 78 65 } //01 00  fuckyouware.exe
		$a_80_3 = {63 7a 35 36 39 35 34 2e 74 77 31 2e 72 75 2f 49 43 53 68 61 72 70 43 6f 64 65 2e 53 68 61 72 70 5a 69 70 4c 69 62 2e 64 6c 6c } //cz56954.tw1.ru/ICSharpCode.SharpZipLib.dll  00 00 
	condition:
		any of ($a_*)
 
}