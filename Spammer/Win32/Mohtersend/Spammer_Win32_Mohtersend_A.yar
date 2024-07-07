
rule Spammer_Win32_Mohtersend_A{
	meta:
		description = "Spammer:Win32/Mohtersend.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 74 6f 72 53 65 6e 64 53 70 61 6d } //1 MotorSendSpam
		$a_01_1 = {45 78 65 63 75 74 61 4d 6f 74 6f 72 53 65 6e 64 53 70 61 6d 53 68 65 6c 6c } //1 ExecutaMotorSendSpamShell
		$a_01_2 = {45 78 65 63 4d 65 74 68 6f 64 } //1 ExecMethod
		$a_01_3 = {54 58 4d 61 69 6c 53 68 65 6c 6c } //1 TXMailShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}