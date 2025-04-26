
rule Trojan_Win32_Fragtor_NB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 6f 74 68 20 79 6f 75 72 20 6d 6f 6d 20 61 72 65 20 66 61 47 47 30 74 73 20 3a 29 } //5 Both your mom are faGG0ts :)
		$a_81_1 = {67 75 6f 63 70 5f 77 66 66 67 6a 5f 74 75 6f } //5 guocp_wffgj_tuo
		$a_81_2 = {6c 69 62 71 75 78 70 76 69 33 32 2e 64 6c 6c } //5 libquxpvi32.dll
		$a_81_3 = {67 63 72 79 5f 70 6b 5f 65 6e 63 72 79 70 74 } //5 gcry_pk_encrypt
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5) >=20
 
}