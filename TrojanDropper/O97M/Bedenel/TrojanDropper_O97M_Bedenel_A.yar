
rule TrojanDropper_O97M_Bedenel_A{
	meta:
		description = "TrojanDropper:O97M/Bedenel.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 5c 22 20 2b 20 43 53 74 72 28 28 32 31 34 37 34 38 33 36 34 38 23 20 2a 20 52 6e 64 29 20 2b 20 31 29 20 2b 20 22 2e 31 22 } //1 + "\" + CStr((2147483648# * Rnd) + 1) + ".1"
		$a_01_1 = {27 77 2e 45 78 65 63 20 28 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 74 6d 70 66 69 6c 65 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2c 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 20 68 6f 73 74 20 30 30 30 30 30 30 30 30 30 30 30 30 22 29 } //1 'w.Exec ("rundll32.exe " + Chr(34) + tmpfile + Chr(34) + ",DllGetClassObject host 000000000000")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}