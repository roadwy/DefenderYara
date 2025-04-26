
rule Trojan_BAT_PowerkatzInj_RS_MTB{
	meta:
		description = "Trojan:BAT/PowerkatzInj.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 5f 00 64 00 6f 00 74 00 6e 00 65 00 74 00 32 00 6a 00 73 00 } //1 shellcode_dotnet2js
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 GetProcessById
		$a_01_2 = {49 6e 6a 65 63 74 44 4c 4c } //1 InjectDLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}