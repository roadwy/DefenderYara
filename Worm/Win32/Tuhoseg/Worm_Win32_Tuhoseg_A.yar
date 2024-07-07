
rule Worm_Win32_Tuhoseg_A{
	meta:
		description = "Worm:Win32/Tuhoseg.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {ac 8b da 81 e3 ff 00 00 00 32 d8 c1 e3 02 c1 ea 08 81 e2 ff ff ff 00 33 93 90 01 04 e2 e1 8b c2 90 00 } //1
		$a_01_1 = {e8 0c 00 00 00 73 63 76 68 6f 73 73 2e 65 78 65 00 e8 } //1
		$a_01_2 = {c7 07 73 63 76 68 c7 47 04 6f 73 73 2e c7 47 08 65 78 65 00 c7 47 0c 00 00 00 00 } //1
		$a_01_3 = {6f 62 6a 52 65 67 2e 53 65 74 53 74 72 69 6e 67 56 61 6c 75 65 28 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 2c 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 2c 22 53 79 73 74 65 6d 49 6e 5f 31 22 2c 22 25 73 22 29 } //1 objReg.SetStringValue(HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Run","SystemIn_1","%s")
		$a_01_4 = {e8 0b 00 00 00 72 75 6e 32 5f 31 2e 62 61 74 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}