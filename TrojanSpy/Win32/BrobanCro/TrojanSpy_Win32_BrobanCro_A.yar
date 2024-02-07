
rule TrojanSpy_Win32_BrobanCro_A{
	meta:
		description = "TrojanSpy:Win32/BrobanCro.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 65 6c 67 6f 6f 47 5c 74 66 6f 73 6f 72 63 69 4d 5c } //01 00  \elgooG\tfosorciM\
		$a_01_1 = {67 6e 70 2e 6e 6f 63 69 } //01 00  gnp.noci
		$a_01_2 = {6e 6f 73 6a 2e 74 73 65 66 69 6e 61 4d } //01 00  nosj.tsefinaM
		$a_01_3 = {5c 73 6f 76 69 74 61 63 69 6c 70 61 20 65 64 20 73 6f 64 61 44 5c } //0a 00  \sovitacilpa ed sodaD\
		$a_01_4 = {6f 44 6f 63 2e 69 6e 64 65 78 4f 66 28 22 4c 4f 43 41 4c 20 44 45 20 50 41 47 41 4d 45 4e 54 4f 22 29 } //0a 00  oDoc.indexOf("LOCAL DE PAGAMENTO")
		$a_01_5 = {30 3c 3d 6c 2e 69 6e 64 65 78 4f 66 28 66 28 22 59 42 50 4e 59 20 51 52 20 43 4e 54 4e 5a 52 41 47 42 22 29 } //0a 00  0<=l.indexOf(f("YBPNY QR CNTNZRAGB")
		$a_03_6 = {2e 73 69 63 6f 6f 62 2e 63 6f 6d 2e 62 72 2f 90 02 08 76 61 72 20 75 72 6c 64 61 76 65 7a 54 69 74 75 6c 6f 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 } //ce 27 
	condition:
		any of ($a_*)
 
}