
rule Ransom_Win32_Chaos_BMX_MTB{
	meta:
		description = "Ransom:Win32/Chaos.BMX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_01_1 = {63 68 61 6f 73 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 chaos@protonmail.com
		$a_01_2 = {72 65 63 6f 76 65 72 20 79 6f 75 72 20 64 61 74 61 } //1 recover your data
		$a_01_3 = {43 00 68 00 61 00 6f 00 73 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } //1 ChaosClipboardMonitor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}