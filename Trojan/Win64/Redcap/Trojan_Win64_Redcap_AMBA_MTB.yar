
rule Trojan_Win64_Redcap_AMBA_MTB{
	meta:
		description = "Trojan:Win64/Redcap.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 02 d9 44 02 df 41 0f b6 cb 0f b6 44 8d 08 41 30 46 ff 8b 44 8d 08 31 44 95 08 42 8b 44 a5 08 41 8d 0c 00 42 31 4c 95 08 49 ff cf } //00 00 
	condition:
		any of ($a_*)
 
}