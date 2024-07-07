
rule Trojan_BAT_Kryptik_UN_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.UN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {13 21 11 21 19 8d 90 01 04 25 16 7e 90 01 04 a2 25 17 7e 90 01 04 a2 25 18 72 90 01 04 a2 28 90 01 04 26 20 90 01 04 0a 2b 00 06 2a 90 00 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
		$a_80_3 = {4c 61 74 65 43 61 6c 6c } //LateCall  2
		$a_80_4 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //NewLateBinding  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}