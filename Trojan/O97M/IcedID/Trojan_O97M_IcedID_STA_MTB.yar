
rule Trojan_O97M_IcedID_STA_MTB{
	meta:
		description = "Trojan:O97M/IcedID.STA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 69 76 65 58 4f 62 6a 65 63 74 28 65 78 63 65 70 74 69 6f 6e 4e 61 6d 65 73 70 61 63 65 45 78 63 65 70 74 69 6f 6e 29 29 3b } //01 00  = "tiveXObject(exceptionNamespaceException));
		$a_01_1 = {3d 20 22 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 3b 20 76 61 72 20 4c 3d 73 2e 6c 65 6e 67 74 68 3b 76 61 72 20 64 61 74 61 62 61 73 65 4c 69 6e 6b 20 3d 20 27 63 68 61 72 41 74 27 3b } //01 00  = "ng.fromCharCode; var L=s.length;var databaseLink = 'charAt';
		$a_01_2 = {3d 20 22 61 72 54 61 62 6c 65 4c 65 66 74 28 63 6c 65 61 72 43 6f 6c 6c 65 63 74 69 6f 6e 43 6f 75 6e 74 65 72 29 7b 72 65 74 75 72 6e 20 63 6c 65 61 72 43 6f 6c 6c 65 63 74 69 6f 6e 43 6f 75 6e 74 65 72 2e 73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b } //01 00  = "arTableLeft(clearCollectionCounter){return clearCollectionCounter.split('').reverse().join('');
		$a_01_3 = {3d 20 22 27 29 2e 69 6e 6e 65 72 48 54 4d 4c 3b 76 61 72 20 63 6c 61 73 73 47 6c 6f 62 61 6c 43 6f 6e 76 65 72 74 20 3d 20 63 6c 61 73 73 47 6c 6f 62 61 6c 43 6f 6e 76 65 72 74 2e 73 70 6c 69 74 28 27 7c 27 29 } //01 00  = "').innerHTML;var classGlobalConvert = classGlobalConvert.split('|')
		$a_01_4 = {3d 20 22 74 65 78 74 62 6f 78 43 6f 6c 6c 65 63 74 69 6f 6e 28 74 6d 70 43 6f 75 6e 74 29 } //00 00  = "textboxCollection(tmpCount)
	condition:
		any of ($a_*)
 
}