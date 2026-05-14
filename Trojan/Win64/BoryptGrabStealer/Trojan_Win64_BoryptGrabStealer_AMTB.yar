
rule Trojan_Win64_BoryptGrabStealer_AMTB{
	meta:
		description = "Trojan:Win64/BoryptGrabStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 34 35 2e 39 33 2e 32 30 2e 36 31 3a 35 34 36 36 2f 61 70 69 2f } //http://45.93.20.61:5466/api/  3
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_2 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //-WindowStyle Hidden  1
		$a_80_3 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //-ExecutionPolicy Bypass  1
		$a_80_4 = {2d 43 6f 6d 6d 61 6e 64 20 22 } //-Command "  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}