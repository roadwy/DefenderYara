
rule Trojan_Win32_BadJoke_DAB_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d3 eb 89 d8 83 e0 03 89 c1 d3 ea 89 d0 89 c1 8d 95 ?? ?? ?? ?? 8b 45 f4 01 d0 88 08 83 45 f4 01 81 7d f4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}