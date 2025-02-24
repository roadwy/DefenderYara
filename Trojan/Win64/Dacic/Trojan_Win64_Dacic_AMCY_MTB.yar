
rule Trojan_Win64_Dacic_AMCY_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 66 0f 1f 84 00 00 00 00 00 b8 ?? ?? ?? ?? 4d 8d 40 01 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 ff c1 2a c2 04 35 41 30 40 ff 83 f9 1d 7c } //3
		$a_80_1 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 66 } //taskkill.exe /f  1
		$a_80_2 = {5a 63 5f 41 6e 74 69 48 69 74 62 6f 78 } //Zc_AntiHitbox  1
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}