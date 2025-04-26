
rule Trojan_Win32_LummaStealer_RP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 55 6c 68 4d 46 79 44 64 6f 7a } //1 main.UlhMFyDdoz
		$a_01_1 = {6d 61 69 6e 2e 41 45 4b 43 69 68 61 4c 52 56 } //1 main.AEKCihaLRV
		$a_01_2 = {6d 61 69 6e 2e 75 79 64 69 4f 59 67 51 43 48 2e 64 65 66 65 72 77 72 61 70 32 } //10 main.uydiOYgQCH.deferwrap2
		$a_01_3 = {6d 61 69 6e 2e 75 79 64 69 4f 59 67 51 43 48 2e 64 65 66 65 72 77 72 61 70 31 } //10 main.uydiOYgQCH.deferwrap1
		$a_01_4 = {6d 61 69 6e 2e 6d 4f 61 53 6a 73 67 44 6e 79 2e 66 75 6e 63 31 2e 50 72 69 6e 74 2e 31 } //10 main.mOaSjsgDny.func1.Print.1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=32
 
}