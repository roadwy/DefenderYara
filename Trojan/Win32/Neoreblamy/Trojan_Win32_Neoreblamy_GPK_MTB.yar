
rule Trojan_Win32_Neoreblamy_GPK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {6f 61 78 7a 4b 4c 62 46 41 57 50 62 67 51 73 47 78 48 46 } //3 oaxzKLbFAWPbgQsGxHF
		$a_81_1 = {70 52 62 72 56 62 57 4b 6c 4d 6f 51 48 4b 4c 55 69 44 61 6d 7a 58 } //2 pRbrVbWKlMoQHKLUiDamzX
		$a_81_2 = {5a 54 51 6d 76 54 65 4e 7a 48 74 6d 5a 74 44 4b 69 57 52 6b 42 6a 6d 53 68 74 4c 57 4d 76 } //1 ZTQmvTeNzHtmZtDKiWRkBjmShtLWMv
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}