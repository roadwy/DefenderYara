
rule Trojan_Win32_RunnySlip_B_dha{
	meta:
		description = "Trojan:Win32/RunnySlip.B!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 61 73 65 36 34 2d 35 2d 73 74 65 70 2d 74 63 70 2d 73 68 65 6c 6c 2d 64 65 63 6f 64 65 2d 65 78 65 63 75 74 65 2d 63 6c 69 65 6e 74 } //3 base64-5-step-tcp-shell-decode-execute-client
	condition:
		((#a_01_0  & 1)*3) >=3
 
}