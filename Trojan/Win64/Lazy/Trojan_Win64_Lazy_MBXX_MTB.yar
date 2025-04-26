
rule Trojan_Win64_Lazy_MBXX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MBXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 6b 74 6f 70 5c 73 6f 6c 6f 5c 65 78 61 6d 70 6c 65 73 5c 65 78 61 6d 70 6c 65 5f 77 69 6e 33 32 5f 64 69 72 65 63 74 78 31 31 5c 52 65 6c 65 61 73 65 5c 63 61 6c 63 75 6c 61 74 6f 72 2e 70 } //10 Desktop\solo\examples\example_win32_directx11\Release\calculator.p
	condition:
		((#a_01_0  & 1)*10) >=10
 
}