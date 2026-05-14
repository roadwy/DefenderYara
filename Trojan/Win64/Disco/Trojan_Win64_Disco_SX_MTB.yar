
rule Trojan_Win64_Disco_SX_MTB{
	meta:
		description = "Trojan:Win64/Disco.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 57 65 62 63 61 6d 20 73 74 72 65 61 6d 69 6e 67 20 73 74 61 72 74 65 64 } //10 [+] Webcam streaming started
		$a_01_1 = {5b 2d 5d 20 53 63 72 65 65 6e 20 73 74 72 65 61 6d 69 6e 67 } //10 [-] Screen streaming
		$a_81_2 = {52 65 6d 6f 74 65 43 68 61 74 57 6e 64 } //5 RemoteChatWnd
		$a_81_3 = {4a 75 6d 70 73 63 61 72 65 43 6c 73 } //1 JumpscareCls
		$a_81_4 = {42 6c 61 6e 6b 53 63 72 65 65 6e 43 6c 73 } //1 BlankScreenCls
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=27
 
}