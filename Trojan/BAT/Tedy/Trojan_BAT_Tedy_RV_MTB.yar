
rule Trojan_BAT_Tedy_RV_MTB{
	meta:
		description = "Trojan:BAT/Tedy.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 50 69 6c 6c 61 67 65 72 5f 5c 50 69 6c 6c 61 67 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 69 6c 6c 61 67 65 72 2e 70 64 62 } //1 C:\Users\Administrator\Desktop\Pillager_\Pillager\obj\Debug\Pillager.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}