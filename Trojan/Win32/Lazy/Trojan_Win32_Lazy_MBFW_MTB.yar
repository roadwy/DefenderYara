
rule Trojan_Win32_Lazy_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 78 71 64 61 6e 6a 6c 6e 69 61 66 72 68 63 7a 73 72 63 79 79 69 78 74 6b 79 69 71 77 67 74 66 66 66 72 77 6c 6e 6d 6f 78 6d 63 77 6f 78 67 6a 68 6a 70 76 71 76 61 77 77 61 66 74 69 76 74 61 76 6a 78 } //1 serxqdanjlniafrhczsrcyyixtkyiqwgtfffrwlnmoxmcwoxgjhjpvqvawwaftivtavjx
	condition:
		((#a_01_0  & 1)*1) >=1
 
}