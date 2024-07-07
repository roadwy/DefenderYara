
rule Trojan_Win32_MBRLock_EP_MTB{
	meta:
		description = "Trojan:Win32/MBRLock.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 47 20 50 61 73 73 77 6f 72 64 20 77 6f 73 68 69 78 69 61 6f 78 75 65 73 68 65 6e 67 } //2 LG Password woshixiaoxuesheng
		$a_01_1 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 21 21 50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 } //2 Your disk have a lock!!!Please enter the unlock password
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}