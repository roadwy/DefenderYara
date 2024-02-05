
rule Trojan_BAT_Tiny_AB_MTB{
	meta:
		description = "Trojan:BAT/Tiny.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //SecurityProtocolType  03 00 
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  03 00 
		$a_80_2 = {49 4f 51 69 77 62 65 71 69 62 77 71 77 65 78 71 77 65 76 } //IOQiwbeqibwqwexqwev  03 00 
		$a_80_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //DynamicInvoke  03 00 
		$a_80_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 52 65 67 53 76 63 73 2e 65 78 65 } //C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe  03 00 
		$a_80_5 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 } //cdn.discordapp  03 00 
		$a_80_6 = {53 65 72 76 69 63 65 50 6f 69 6e 74 4d 61 6e 61 67 65 72 } //ServicePointManager  00 00 
	condition:
		any of ($a_*)
 
}