
rule Trojan_Win32_Farfli_BS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 8a ca 03 c6 32 08 02 ca 46 3b 74 24 0c 88 08 7c } //02 00 
		$a_01_1 = {63 72 61 63 6b 65 64 20 62 79 20 78 69 6d 6f } //00 00  cracked by ximo
	condition:
		any of ($a_*)
 
}