
rule Trojan_AndroidOS_Banker_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {ff 97 a8 c8 8d d2 28 4c ac f2 88 ad cc f2 88 0c e0 f2 08 6b 20 f8 e0 a3 00 91 7a fe ff 97 68 aa 8c d2 88 8e ae f2 28 cd cd f2 e8 0c e0 f2 08 6b 20 f8 88 02 40 f9 e3 00 00 b0 63 24 16 91 e2 a3 00 91 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}