
rule Trojan_Win32_IcedID_GZM_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {52 31 ff 2b 39 f7 df 83 c1 ?? 83 ef ?? 31 c7 83 ef ?? 31 c0 29 f8 f7 d8 89 3a 83 ea ?? 83 c6 ?? 83 fe ?? 75 dc } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}