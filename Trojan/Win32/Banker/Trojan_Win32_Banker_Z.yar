
rule Trojan_Win32_Banker_Z{
	meta:
		description = "Trojan:Win32/Banker.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 72 61 73 69 6c 2e 65 78 65 } //1 Brasil.exe
		$a_02_1 = {42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 [0-10] 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 [0-08] 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 } //1
		$a_01_2 = {54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 } //1 TMethodImplementationIntercept
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}