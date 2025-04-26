
rule Trojan_Win32_Stealc_GPAA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {51 32 39 75 64 47 56 75 64 43 31 55 65 58 42 6c 4f 69 42 74 64 57 78 30 61 58 42 68 63 6e 51 76 5a 6d 39 79 62 53 31 6b 59 58 52 68 4f 79 42 69 62 33 56 75 5a 47 46 79 65 54 30 74 4c 53 30 74 } //2 Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0tLS0t
		$a_81_1 = {61 48 52 30 63 44 6f 76 4c 33 4a 76 59 6d 56 79 64 47 70 76 61 47 35 7a 62 32 34 75 64 47 39 77 } //2 aHR0cDovL3JvYmVydGpvaG5zb24udG9w
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}