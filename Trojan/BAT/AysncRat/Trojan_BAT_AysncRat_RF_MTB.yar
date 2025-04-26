
rule Trojan_BAT_AysncRat_RF_MTB{
	meta:
		description = "Trojan:BAT/AysncRat.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 0d 02 06 02 06 91 03 59 d2 9c 06 17 58 0a 06 02 8e 69 32 ed } //5
		$a_01_1 = {66 61 6b 5f 63 68 65 61 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 66 61 6b 5f 63 68 65 61 2e 70 64 62 } //1 fak_chea\obj\x86\Release\fak_chea.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}