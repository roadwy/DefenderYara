
rule Trojan_Win64_CobaltStrike_KKM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 43 78 2b 83 d0 00 00 00 01 43 20 b8 90 01 04 2b 43 4c 89 83 04 01 00 00 8b 4b 20 8b 83 98 00 00 00 ff c1 0f af c1 89 83 98 00 00 00 49 81 f9 90 01 04 0f 8c 90 00 } //1
		$a_01_1 = {6e 66 76 75 72 67 38 35 36 6c 6b 36 33 2e 64 6c 6c } //1 nfvurg856lk63.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}