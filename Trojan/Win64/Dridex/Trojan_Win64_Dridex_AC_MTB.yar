
rule Trojan_Win64_Dridex_AC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {70 5a 36 72 36 4b 45 49 43 49 4f 68 68 75 72 50 66 6d 65 68 7a 7a 2e 70 64 62 } //pZ6r6KEICIOhhurPfmehzz.pdb  03 00 
		$a_80_1 = {47 69 72 65 6e 64 65 72 69 6e 67 6d 65 64 34 61 76 61 69 6c 61 62 6c 65 78 78 72 65 6c 65 61 73 65 } //Girenderingmed4availablexxrelease  03 00 
		$a_80_2 = {62 6c 6f 67 67 65 72 73 43 68 72 6f 6d 65 78 4f 77 61 73 50 4e } //bloggersChromexOwasPN  03 00 
		$a_80_3 = {52 68 46 69 72 65 66 6f 78 2c 33 4f 6e 4f 47 6f 6f 67 6c 65 4c 74 } //RhFirefox,3OnOGoogleLt  03 00 
		$a_80_4 = {43 61 74 65 67 6f 72 79 3a 47 6f 6f 67 6c 65 63 6f 6d 70 75 74 65 72 4a 50 } //Category:GooglecomputerJP  03 00 
		$a_80_5 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //Explorer_Server  03 00 
		$a_80_6 = {47 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 47 72 6f 75 70 } //GetSecurityDescriptorGroup  00 00 
	condition:
		any of ($a_*)
 
}