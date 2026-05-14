
rule Trojan_BAT_Injector_KKA_MTB{
	meta:
		description = "Trojan:BAT/Injector.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_81_0 = {69 73 6d 2e 70 75 74 65 53 74 6e 65 69 6c 43 2e 74 63 65 6e 6e 6f 43 6e 65 65 72 63 53 5c 70 6d 65 54 5c 3a 43 20 69 2f 27 20 65 78 65 2e 63 65 78 65 69 73 6d 20 73 73 65 63 6f 72 50 2d 74 72 61 74 53 20 3b 27 69 73 6d 2e 70 75 74 65 53 74 6e 65 69 6c 43 2e 74 63 65 6e 6e 6f 43 6e 65 65 72 63 53 5c 70 6d 65 54 5c 3a 43 27 20 6f 2d } //20 ism.puteStneilC.tcennoCneercS\pmeT\:C i/' exe.cexeism ssecorP-tratS ;'ism.puteStneilC.tcennoCneercS\pmeT\:C' o-
		$a_81_1 = {4c 2d 20 65 78 65 2e 6c 72 75 63 20 3b 6c 6c 75 4e 2d 74 75 4f 20 7c 20 65 63 72 6f 46 2d 20 27 70 6d 65 54 5c 3a 43 27 20 68 74 61 50 2d 20 79 72 6f 74 63 65 72 69 44 20 65 70 79 54 6d 65 74 49 } //15 L- exe.lruc ;lluN-tuO | ecroF- 'pmeT\:C' htaP- yrotceriD epyTmetI
		$a_81_2 = {6d 65 74 49 2d 77 65 4e 3b 38 20 73 64 6e 6f 63 65 53 2d 20 70 65 65 6c 53 2d 74 72 61 74 53 3b 65 63 72 6f 46 2d 20 73 24 20 6e 6f 69 73 6e 65 74 78 45 6e 6f 69 73 75 6c 63 78 45 2d 20 29 65 72 75 74 63 75 72 74 53 61 74 61 44 65 74 65 72 63 6e 6f 43 24 } //10 metI-weN;8 sdnoceS- peelS-tratS;ecroF- s$ noisnetxEnoisulcxE- )erutcurtSataDetercnoC$
		$a_81_3 = {3a 77 65 6e 21 72 6f 74 61 72 74 73 69 6e 69 6d 64 41 3a 6e 6f 69 74 61 76 65 6c 45 } //5 :wen!rotartsinimdA:noitavelE
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5) >=50
 
}