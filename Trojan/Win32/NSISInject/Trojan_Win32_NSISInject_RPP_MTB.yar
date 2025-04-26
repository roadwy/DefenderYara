
rule Trojan_Win32_NSISInject_RPP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 65 70 6f 6e 65 72 69 6e 67 73 6d 75 6c 69 67 68 65 64 } //1 Deponeringsmulighed
		$a_81_1 = {42 6c 75 64 67 65 5c 4e 6f 6e 73 70 69 6e 6f 73 65 31 37 30 5c 4e 6f 6d 69 6e 61 74 69 76 61 6c 38 30 2e 69 6e 69 } //1 Bludge\Nonspinose170\Nominatival80.ini
		$a_81_2 = {42 6f 77 65 72 79 69 73 68 32 32 31 2e 6c 6e 6b } //1 Boweryish221.lnk
		$a_81_3 = {43 61 64 77 61 6c 2e 52 65 69 } //1 Cadwal.Rei
		$a_81_4 = {44 65 6c 69 67 68 74 65 72 2e 49 6e 67 34 35 } //1 Delighter.Ing45
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RPP_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 61 6c 6c 65 70 72 65 73 73 65 72 6e 65 } //1 Ballepresserne
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 44 75 65 6c 69 67 68 65 64 73 74 65 67 6e 5c 41 6e 64 65 6e 70 72 6d 69 65 73 5c 52 61 62 62 69 6e 61 74 65 72 6e 65 73 } //1 Software\Duelighedstegn\Andenprmies\Rabbinaternes
		$a_81_2 = {4f 76 65 72 73 65 6e 73 69 74 69 76 69 74 79 31 34 } //1 Oversensitivity14
		$a_81_3 = {47 6c 64 65 73 73 6b 72 69 67 31 37 34 2e 4f 6d 6b } //1 Gldesskrig174.Omk
		$a_81_4 = {4f 76 65 72 70 75 6e 63 68 65 64 2e 42 61 72 } //1 Overpunched.Bar
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RPP_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 6a 00 73 00 69 00 6b 00 6b 00 65 00 72 00 74 00 5c 00 43 00 6f 00 75 00 72 00 69 00 65 00 72 00 73 00 } //1 Stjsikkert\Couriers
		$a_01_1 = {44 00 72 00 6f 00 6c 00 6c 00 69 00 73 00 68 00 2e 00 61 00 64 00 73 00 } //1 Drollish.ads
		$a_01_2 = {41 00 6e 00 74 00 69 00 70 00 73 00 61 00 6c 00 6d 00 69 00 73 00 74 00 2e 00 46 00 69 00 72 00 } //1 Antipsalmist.Fir
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 6e 00 74 00 69 00 6d 00 61 00 6e 00 69 00 61 00 63 00 61 00 6c 00 5c 00 42 00 6f 00 67 00 6c 00 61 00 64 00 65 00 70 00 72 00 69 00 73 00 65 00 6e 00 73 00 5c 00 49 00 6e 00 61 00 64 00 76 00 69 00 73 00 61 00 62 00 69 00 6c 00 69 00 74 00 79 00 } //1 Software\Antimaniacal\Bogladeprisens\Inadvisability
		$a_01_4 = {41 00 6d 00 70 00 65 00 72 00 65 00 2e 00 69 00 6e 00 69 00 } //1 Ampere.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}