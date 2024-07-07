
rule Trojan_Win64_GoShell_GZX_MTB{
	meta:
		description = "Trojan:Win64/GoShell.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 58 30 01 02 58 31 01 02 44 6f 01 02 58 32 01 02 58 33 01 02 50 43 00 02 73 70 00 02 70 } //10 堂İ堂ı䐂ů堂Ĳ堂ĳ倂C猂p瀂
	condition:
		((#a_01_0  & 1)*10) >=10
 
}