
rule Trojan_Win32_RootkitDrv_ARA_MTB{
	meta:
		description = "Trojan:Win32/RootkitDrv.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 4e 46 6c 79 36 31 35 2e 65 78 65 } //C:\WINDOWS\SYSTEM32\DNFly615.exe  2
		$a_01_1 = {43 54 46 4e 4f 4d 2e 65 78 65 2f 43 54 46 4e 30 4d 2e 65 78 65 2f 43 54 46 4d 4f 4d 2e 65 78 65 2f 43 54 46 4d 30 4d 2e 65 78 65 2f 43 54 46 4d 30 4e 2e 65 78 65 2f 43 49 46 4d 4f 4d 2e 65 78 65 2f 43 49 46 4e 30 4e 2e 65 78 65 2f 44 4e 46 6c 79 36 31 35 2e 65 78 65 } //2 CTFNOM.exe/CTFN0M.exe/CTFMOM.exe/CTFM0M.exe/CTFM0N.exe/CIFMOM.exe/CIFN0N.exe/DNFly615.exe
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}