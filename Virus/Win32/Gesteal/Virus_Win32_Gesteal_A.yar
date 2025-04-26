
rule Virus_Win32_Gesteal_A{
	meta:
		description = "Virus:Win32/Gesteal.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 41 68 02 00 00 80 8d 87 d4 d2 ff ff ff 10 85 c0 75 2b 8b 1e 8b 4e 08 85 c9 74 17 85 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}