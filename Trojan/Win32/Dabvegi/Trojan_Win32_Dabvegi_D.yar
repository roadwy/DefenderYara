
rule Trojan_Win32_Dabvegi_D{
	meta:
		description = "Trojan:Win32/Dabvegi.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 65 73 45 6d 70 5f 30 } //1 besEmp_0
		$a_01_1 = {52 6e 64 53 74 72 69 6e 67 } //1 RndString
		$a_01_2 = {56 65 72 69 66 69 63 61 5f 53 74 61 74 75 73 } //1 Verifica_Status
		$a_01_3 = {70 61 73 73 63 68 61 72 } //1 passchar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}