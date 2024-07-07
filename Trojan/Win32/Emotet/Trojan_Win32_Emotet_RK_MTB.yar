
rule Trojan_Win32_Emotet_RK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {4b 41 21 63 52 37 52 53 40 6c 74 47 32 25 61 6d 40 2a 50 78 70 48 25 39 45 25 25 38 78 76 67 56 74 6a 4f 48 66 2b 51 6f 71 74 52 59 71 6b 55 73 4b 4e 6b 21 72 51 5a 53 73 23 53 33 32 3c 61 79 6c 66 54 7a 57 43 2b 46 2a 69 4c 77 30 36 2b 30 45 52 4c 3e 5e 57 44 65 23 59 32 59 2b 70 64 72 24 28 6a 4b 4c 46 2a } //KA!cR7RS@ltG2%am@*PxpH%9E%%8xvgVtjOHf+QoqtRYqkUsKNk!rQZSs#S32<aylfTzWC+F*iLw06+0ERL>^WDe#Y2Y+pdr$(jKLF*  1
		$a_03_1 = {81 ca 00 10 00 00 52 56 53 6a ff ff 15 90 01 04 eb 0f 6a 40 68 00 30 00 00 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}