
rule Trojan_Win64_Radthief_KK_MTB{
	meta:
		description = "Trojan:Win64/Radthief.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 d0 48 f7 e9 48 01 ca 48 d1 fa 49 89 c9 48 c1 f9 ?? 48 29 ca 48 8d 14 52 4d 89 ca 49 29 d1 49 39 f0 } //20
		$a_03_1 = {49 89 d0 48 f7 ea 48 c1 fa ?? 48 69 d2 ?? ?? 00 00 4d 89 c1 49 29 d0 49 8d 90 90 ?? ?? 00 00 48 39 d1 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Radthief_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Radthief.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 ff c1 48 8d 1c 40 48 8d 34 58 48 8d 1c 58 48 8d 5b 0d 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 eb 48 8d 3c 16 48 8d 7f 0d 48 c1 ff ?? 48 c1 fb ?? 48 29 df 48 89 fb 48 c1 e7 ?? 48 29 df 48 29 fe 48 8d 46 0d } //20
		$a_03_1 = {48 ff c1 48 89 c3 48 83 e0 ?? 48 01 c2 48 c1 fb ?? 48 89 d8 } //10
		$a_01_2 = {47 65 74 49 6e 73 74 61 6c 6c 44 65 74 61 69 6c 73 50 61 79 6c 6f 61 64 } //5 GetInstallDetailsPayload
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}