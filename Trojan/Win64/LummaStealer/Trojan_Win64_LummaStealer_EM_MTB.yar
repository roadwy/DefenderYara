
rule Trojan_Win64_LummaStealer_EM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {49 30 32 4f 70 32 65 36 5a 44 35 32 4f 4a 49 6e 56 6f 6c 46 2f 57 68 57 77 47 55 67 75 6b 76 61 77 54 4c 48 63 53 34 71 70 } //1 I02Op2e6ZD52OJInVolF/WhWwGUgukvawTLHcS4qp
		$a_81_1 = {50 57 47 56 75 6f 49 42 64 62 2f 63 6f 72 65 5f 69 6e 6a 65 63 74 6f 72 2e 67 6f } //1 PWGVuoIBdb/core_injector.go
		$a_81_2 = {50 57 47 56 75 6f 49 42 64 62 2f 69 6e 6a 65 63 74 69 6f 6e 2e 67 6f } //1 PWGVuoIBdb/injection.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}