
rule Trojan_Win32_Ursnif_VN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 56 45 52 49 20 46 41 44 4f 2c 20 54 4f 56 } //1 DVERI FADO, TOV
		$a_81_1 = {61 64 6d 69 6e 40 64 76 65 72 69 66 61 64 6f 74 6f 76 2e 73 70 61 63 65 } //1 admin@dverifadotov.space
		$a_81_2 = {42 75 64 2e 20 31 31 35 20 70 72 6f 73 70 65 6b 74 20 47 61 67 61 72 69 6e 61 } //1 Bud. 115 prospekt Gagarina
		$a_81_3 = {44 6e 69 70 72 6f 70 65 74 72 6f 76 73 6b 20 4f 62 6c 61 73 74 } //1 Dnipropetrovsk Oblast
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}