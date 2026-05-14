
rule Trojan_Win32_Schellcoderunner_RR_MTB{
	meta:
		description = "Trojan:Win32/Schellcoderunner.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 00 72 00 6f 00 6f 00 64 00 6c 00 65 00 73 00 70 00 68 00 65 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 froodlesphere.com
		$a_00_1 = {71 00 75 00 69 00 78 00 6c 00 79 00 6e 00 65 00 73 00 74 00 2e 00 63 00 6f 00 6d 00 } //1 quixlynest.com
		$a_00_2 = {7a 00 65 00 6e 00 74 00 6f 00 70 00 69 00 61 00 63 00 72 00 61 00 66 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 zentopiacrafts.com
		$a_01_3 = {5c 53 79 73 74 65 6d 33 32 5c 73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 72 75 6e 20 2f 74 6e 20 22 57 69 6e 64 6f 77 73 55 70 67 72 61 64 65 57 6f 72 6b 65 72 22 } //1 \System32\schtasks.exe /run /tn "WindowsUpgradeWorker"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}