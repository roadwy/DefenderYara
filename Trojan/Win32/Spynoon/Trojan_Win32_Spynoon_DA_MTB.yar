
rule Trojan_Win32_Spynoon_DA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 d9 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d } //2
		$a_01_1 = {48 6b 63 6f 65 64 63 6c 78 66 6b 63 6b 64 6c } //2 Hkcoedclxfkckdl
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}