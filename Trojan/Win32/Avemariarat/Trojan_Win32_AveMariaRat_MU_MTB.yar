
rule Trojan_Win32_AveMariaRat_MU_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6a 64 59 f7 f1 8b 4d 8c 8a 44 15 98 30 04 0f 47 81 ff 00 e8 03 00 7c } //1
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_01_2 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}