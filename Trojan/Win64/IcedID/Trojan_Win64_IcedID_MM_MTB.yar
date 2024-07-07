
rule Trojan_Win64_IcedID_MM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb 3b 48 8b 44 24 40 48 ff c8 eb 61 48 8b 04 24 48 8b 4c 24 08 eb 00 8a 09 88 08 eb 00 48 8b 04 24 48 ff c0 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_MM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 c1 ea 1c 01 d0 83 e0 90 01 01 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 6c 0b 00 00 90 01 01 8b 85 6c 0b 00 00 3b 85 54 0b 00 00 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_MM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ea 89 c8 c1 f8 90 01 01 c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 48 83 c1 01 48 81 f9 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_MM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 49 4f 5f 66 5f 73 73 6c } //1 tIO_f_ssl
		$a_01_1 = {74 49 4f 5f 6e 65 77 5f 62 75 66 66 65 72 5f 73 73 6c 5f 63 6f 6e 6e 65 63 74 } //1 tIO_new_buffer_ssl_connect
		$a_01_2 = {74 49 4f 5f 73 73 6c 5f 63 6f 70 79 5f 73 65 73 73 69 6f 6e 5f 69 64 } //1 tIO_ssl_copy_session_id
		$a_01_3 = {74 49 4f 5f 73 73 6c 5f 73 68 75 74 64 6f 77 6e } //1 tIO_ssl_shutdown
		$a_01_4 = {74 54 4c 53 76 31 5f 32 5f 63 6c 69 65 6e 74 5f 6d 65 74 68 6f 64 } //1 tTLSv1_2_client_method
		$a_01_5 = {74 45 4d 5f 72 65 61 64 5f 53 53 4c 5f 53 45 53 53 49 4f 4e } //1 tEM_read_SSL_SESSION
		$a_01_6 = {74 45 4d 5f 77 72 69 74 65 5f 62 69 6f 5f 53 53 4c 5f 53 45 53 53 49 4f 4e } //1 tEM_write_bio_SSL_SESSION
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}