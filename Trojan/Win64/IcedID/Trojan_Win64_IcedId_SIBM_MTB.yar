
rule Trojan_Win64_IcedId_SIBM_MTB{
	meta:
		description = "Trojan:Win64/IcedId.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f be ca 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 11 33 d2 41 f7 f2 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 41 f7 fa 83 fb ?? 7c } //1
		$a_03_1 = {0f be ca 41 8d 5a ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 01 33 d2 f7 f3 0f be c8 44 0f be c0 41 8b 03 99 44 0f af c1 f7 fb 41 83 fa ?? 7c } //1
		$a_03_2 = {0f be ca 41 8d 72 ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 02 33 d2 f7 f6 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 f7 fe 83 fb ?? 7c } //1
		$a_03_3 = {0f be ca 41 8d 5a ?? 41 0f be c0 0f af c8 41 0f be c0 0f be d1 0f af d0 8b c5 41 00 51 03 33 d2 f7 f3 0f be c8 44 0f be c0 41 8b 43 ?? 99 44 0f af c1 f7 fb 83 fe ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}