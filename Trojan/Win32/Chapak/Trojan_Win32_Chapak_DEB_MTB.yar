
rule Trojan_Win32_Chapak_DEB_MTB{
	meta:
		description = "Trojan:Win32/Chapak.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 78 65 68 75 64 61 76 75 20 79 75 63 75 73 61 66 6f 20 6c 65 64 6f 6d 75 67 69 6d 65 68 65 6d 69 77 61 79 5f 78 65 6b 6f 72 6f 70 20 73 69 2e 70 64 62 } //1 C:\xehudavu yucusafo ledomugimehemiway_xekorop si.pdb
		$a_81_1 = {69 6e 5c 78 75 67 75 6a 6f 64 65 2e 70 64 62 } //1 in\xugujode.pdb
		$a_81_2 = {6e 6f 79 61 6c 61 68 69 70 75 } //1 noyalahipu
		$a_81_3 = {6c 61 79 46 43 69 77 69 6a 61 6a 75 72 6f 7a } //1 layFCiwijajuroz
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}