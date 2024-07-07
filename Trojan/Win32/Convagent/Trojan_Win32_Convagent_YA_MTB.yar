
rule Trojan_Win32_Convagent_YA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 64 72 6f 70 70 65 72 2d 6d 61 73 74 65 72 5c 52 65 6c 65 61 73 65 5c 44 72 6f 70 70 65 72 56 32 2e 70 64 62 } //1 httpdropper-master\Release\DropperV2.pdb
		$a_01_1 = {2f 63 6f 6e 66 69 67 } //1 /config
		$a_01_2 = {2f 54 65 6e 69 6f } //1 /Tenio
		$a_01_3 = {8b 07 3b 45 fc 74 f2 33 c2 8b 55 fc d3 c8 8b c8 89 17 89 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}