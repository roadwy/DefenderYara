
rule Trojan_Win32_MBRLock_NMB_MTB{
	meta:
		description = "Trojan:Win32/MBRLock.NMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 bc 00 00 00 33 db 39 9e 90 01 04 75 13 8d 85 90 01 04 50 e8 0f 8f fe ff 59 89 86 90 01 04 39 5e 78 90 00 } //5
		$a_01_1 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 21 21 50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 } //1 Your disk have a lock!!!Please enter the unlock password
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}