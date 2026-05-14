
rule Trojan_Win32_Virlock_VMX_MTB{
	meta:
		description = "Trojan:Win32/Virlock.VMX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 90 42 46 90 47 49 90 } //5
		$a_01_1 = {88 07 90 46 47 49 83 f9 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}
rule Trojan_Win32_Virlock_VMX_MTB_2{
	meta:
		description = "Trojan:Win32/Virlock.VMX!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 42 } //5
		$a_01_1 = {6a 40 68 00 10 } //5
		$a_01_2 = {46 47 90 49 90 83 f9 00 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10) >=10
 
}
rule Trojan_Win32_Virlock_VMX_MTB_3{
	meta:
		description = "Trojan:Win32/Virlock.VMX!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 90 47 90 49 83 f9 00 0f 85 e7 ff ff ff } //10
		$a_01_1 = {88 07 46 90 47 49 90 83 f9 00 } //10
		$a_01_2 = {42 46 90 47 49 90 83 f9 00 90 } //10
		$a_01_3 = {88 07 90 42 90 46 90 47 90 49 90 83 f9 00 } //10
		$a_01_4 = {8a 06 90 32 c2 88 07 42 } //5
		$a_01_5 = {46 47 49 90 83 f9 00 90 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=10
 
}