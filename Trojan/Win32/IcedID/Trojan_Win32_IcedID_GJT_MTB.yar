
rule Trojan_Win32_IcedID_GJT_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 28 83 ef ?? 8b cf 2b ce 2b ca 83 e9 ?? 88 45 ?? 8b d1 2b d3 83 c2 ?? 8b c1 2b c7 83 e8 ?? 83 c5 ?? 03 f2 83 54 24 ?? ?? 8b d0 2b d6 2b d1 85 ff 75 } //10
		$a_01_1 = {4c 69 73 74 6f 70 65 6e } //1 Listopen
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}