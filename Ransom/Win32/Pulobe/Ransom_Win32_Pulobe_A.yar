
rule Ransom_Win32_Pulobe_A{
	meta:
		description = "Ransom:Win32/Pulobe.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 4d 45 4c 54 5d 5b 54 41 53 4b 4e 41 4d 45 5d } //01 00  [MELT][TASKNAME]
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 21 } //01 00  Your files are Encrypted!
		$a_01_2 = {54 6f 20 62 75 79 20 74 68 65 20 64 65 63 72 79 70 74 6f 72 2c 20 79 6f 75 20 6d 75 73 74 20 70 61 79 20 74 68 65 20 63 6f 73 74 20 6f 66 3a } //01 00  To buy the decryptor, you must pay the cost of:
		$a_01_3 = {6d 73 68 74 61 2e 65 78 65 20 22 6a 61 76 61 73 63 72 69 70 74 3a 6f 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 73 65 74 49 6e 74 65 72 76 61 6c 28 66 75 6e 63 74 69 6f 6e 28 29 7b 74 72 79 7b 6f 2e 52 65 67 57 72 69 74 65 28 27 48 4b 43 55 5c 5c } //00 00  mshta.exe "javascript:o=new ActiveXObject('WScript.Shell');setInterval(function(){try{o.RegWrite('HKCU\\
	condition:
		any of ($a_*)
 
}